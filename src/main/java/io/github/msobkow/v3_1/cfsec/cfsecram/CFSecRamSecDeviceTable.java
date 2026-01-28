
// Description: Java 25 in-memory RAM DbIO implementation for SecDevice.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecDeviceTable in-memory RAM DbIO implementation
 *	for SecDevice.
 */
public class CFSecRamSecDeviceTable
	implements ICFSecSecDeviceTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecDevicePKey,
				CFSecBuffSecDevice > dictByPKey
		= new HashMap< ICFSecSecDevicePKey,
				CFSecBuffSecDevice >();
	private Map< CFSecBuffSecDeviceByNameIdxKey,
			CFSecBuffSecDevice > dictByNameIdx
		= new HashMap< CFSecBuffSecDeviceByNameIdxKey,
			CFSecBuffSecDevice >();
	private Map< CFSecBuffSecDeviceByUserIdxKey,
				Map< CFSecBuffSecDevicePKey,
					CFSecBuffSecDevice >> dictByUserIdx
		= new HashMap< CFSecBuffSecDeviceByUserIdxKey,
				Map< CFSecBuffSecDevicePKey,
					CFSecBuffSecDevice >>();

	public CFSecRamSecDeviceTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecDevice ensureRec(ICFSecSecDevice rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecDevice.CLASS_CODE) {
				return( ((CFSecBuffSecDeviceDefaultFactory)(schema.getFactorySecDevice())).ensureRec(rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecSecDevice createSecDevice( ICFSecAuthorization Authorization,
		ICFSecSecDevice iBuff )
	{
		final String S_ProcName = "createSecDevice";
		
		CFSecBuffSecDevice Buff = ensureRec(iBuff);
		ICFSecSecDevicePKey pkey = schema.getFactorySecDevice().newPKey();
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		pkey.setRequiredDevName( Buff.getRequiredDevName() );
		Buff.setRequiredSecUserId( pkey.getRequiredSecUserId() );
		Buff.setRequiredDevName( pkey.getRequiredDevName() );
		CFSecBuffSecDeviceByNameIdxKey keyNameIdx = (CFSecBuffSecDeviceByNameIdxKey)schema.getFactorySecDevice().newByNameIdxKey();
		keyNameIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyNameIdx.setRequiredDevName( Buff.getRequiredDevName() );

		CFSecBuffSecDeviceByUserIdxKey keyUserIdx = (CFSecBuffSecDeviceByUserIdxKey)schema.getFactorySecDevice().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecDeviceNameIdx",
				"SecDeviceNameIdx",
				keyNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecUserId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"SecDeviceSecUser",
						"SecUser",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

		Map< CFSecBuffSecDevicePKey, CFSecBuffSecDevice > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFSecBuffSecDevicePKey, CFSecBuffSecDevice >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecDevice.CLASS_CODE) {
				CFSecBuffSecDevice retbuff = ((CFSecBuffSecDevice)(schema.getFactorySecDevice().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecSecDevice readDerived( ICFSecAuthorization Authorization,
		ICFSecSecDevicePKey PKey )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerived";
		ICFSecSecDevicePKey key = schema.getFactorySecDevice().newPKey();
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		key.setRequiredDevName( PKey.getRequiredDevName() );
		ICFSecSecDevice buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecDevice lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecDevicePKey PKey )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerived";
		CFSecBuffSecDevicePKey key = schema.getFactorySecDevice().newPKey();
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		key.setRequiredDevName( PKey.getRequiredDevName() );
		ICFSecSecDevice buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecDevice[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecDevice.readAllDerived";
		ICFSecSecDevice[] retList = new ICFSecSecDevice[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecDevice > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecSecDevice readDerivedByNameIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String DevName )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerivedByNameIdx";
		CFSecBuffSecDeviceByNameIdxKey key = (CFSecBuffSecDeviceByNameIdxKey)schema.getFactorySecDevice().newByNameIdxKey();
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredDevName( DevName );

		ICFSecSecDevice buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecDevice[] readDerivedByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerivedByUserIdx";
		CFSecBuffSecDeviceByUserIdxKey key = (CFSecBuffSecDeviceByUserIdxKey)schema.getFactorySecDevice().newByUserIdxKey();
		key.setRequiredSecUserId( SecUserId );

		ICFSecSecDevice[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFSecBuffSecDevicePKey, CFSecBuffSecDevice > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new ICFSecSecDevice[ subdictUserIdx.size() ];
			Iterator< CFSecBuffSecDevice > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecDevicePKey, CFSecBuffSecDevice > subdictUserIdx
				= new HashMap< CFSecBuffSecDevicePKey, CFSecBuffSecDevice >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new ICFSecSecDevice[0];
		}
		return( recArray );
	}

	public ICFSecSecDevice readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String DevName )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerivedByIdIdx() ";
		CFSecBuffSecDevicePKey key = schema.getFactorySecDevice().newPKey();
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredDevName( DevName );

		ICFSecSecDevice buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecDevice readBuff( ICFSecAuthorization Authorization,
		ICFSecSecDevicePKey PKey )
	{
		final String S_ProcName = "CFSecRamSecDevice.readBuff";
		ICFSecSecDevice buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecDevice.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecDevice lockBuff( ICFSecAuthorization Authorization,
		ICFSecSecDevicePKey PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecSecDevice buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecDevice.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecDevice[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecDevice.readAllBuff";
		ICFSecSecDevice buff;
		ArrayList<ICFSecSecDevice> filteredList = new ArrayList<ICFSecSecDevice>();
		ICFSecSecDevice[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecDevice.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecDevice[0] ) );
	}

	/**
	 *	Read a page of all the specific SecDevice buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecDevice instances in the database accessible for the Authorization.
	 */
	public ICFSecSecDevice[] pageAllBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecUserId,
		String priorDevName )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecDevice readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String DevName )
	{
		final String S_ProcName = "CFSecRamSecDevice.readBuffByIdIdx() ";
		ICFSecSecDevice buff = readDerivedByIdIdx( Authorization,
			SecUserId,
			DevName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecDevice.CLASS_CODE ) ) {
			return( (ICFSecSecDevice)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecDevice readBuffByNameIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String DevName )
	{
		final String S_ProcName = "CFSecRamSecDevice.readBuffByNameIdx() ";
		ICFSecSecDevice buff = readDerivedByNameIdx( Authorization,
			SecUserId,
			DevName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecDevice.CLASS_CODE ) ) {
			return( (ICFSecSecDevice)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecDevice[] readBuffByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecDevice.readBuffByUserIdx() ";
		ICFSecSecDevice buff;
		ArrayList<ICFSecSecDevice> filteredList = new ArrayList<ICFSecSecDevice>();
		ICFSecSecDevice[] buffList = readDerivedByUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecDevice.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecDevice)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecDevice[0] ) );
	}

	/**
	 *	Read a page array of the specific SecDevice buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecDevice key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecDevice[] pageBuffByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorSecUserId,
		String priorDevName )
	{
		final String S_ProcName = "pageBuffByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecDevice updateSecDevice( ICFSecAuthorization Authorization,
		ICFSecSecDevice iBuff )
	{
		CFSecBuffSecDevice Buff = ensureRec(iBuff);
		CFSecBuffSecDevicePKey pkey = (CFSecBuffSecDevicePKey)schema.getFactorySecDevice().newPKey();
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		pkey.setRequiredDevName( Buff.getRequiredDevName() );
		CFSecBuffSecDevice existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecDevice",
				"Existing record not found",
				"Existing record not found",
				"SecDevice",
				"SecDevice",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecDevice",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecDeviceByNameIdxKey existingKeyNameIdx = (CFSecBuffSecDeviceByNameIdxKey)schema.getFactorySecDevice().newByNameIdxKey();
		existingKeyNameIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyNameIdx.setRequiredDevName( existing.getRequiredDevName() );

		CFSecBuffSecDeviceByNameIdxKey newKeyNameIdx = (CFSecBuffSecDeviceByNameIdxKey)schema.getFactorySecDevice().newByNameIdxKey();
		newKeyNameIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyNameIdx.setRequiredDevName( Buff.getRequiredDevName() );

		CFSecBuffSecDeviceByUserIdxKey existingKeyUserIdx = (CFSecBuffSecDeviceByUserIdxKey)schema.getFactorySecDevice().newByUserIdxKey();
		existingKeyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecDeviceByUserIdxKey newKeyUserIdx = (CFSecBuffSecDeviceByUserIdxKey)schema.getFactorySecDevice().newByUserIdxKey();
		newKeyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Check unique indexes

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecDevice",
					"SecDeviceNameIdx",
					"SecDeviceNameIdx",
					newKeyNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecUserId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecDevice",
						"Container",
						"SecDeviceSecUser",
						"SecUser",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecDevicePKey, CFSecBuffSecDevice > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

		subdict = dictByUserIdx.get( existingKeyUserIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByUserIdx.containsKey( newKeyUserIdx ) ) {
			subdict = dictByUserIdx.get( newKeyUserIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecDevicePKey, CFSecBuffSecDevice >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	public void deleteSecDevice( ICFSecAuthorization Authorization,
		ICFSecSecDevice iBuff )
	{
		final String S_ProcName = "CFSecRamSecDeviceTable.deleteSecDevice() ";
		CFSecBuffSecDevice Buff = ensureRec(iBuff);
		int classCode;
		CFSecBuffSecDevicePKey pkey = (CFSecBuffSecDevicePKey)(Buff.getPKey());
		CFSecBuffSecDevice existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecDevice",
				pkey );
		}
		CFSecBuffSecDeviceByNameIdxKey keyNameIdx = (CFSecBuffSecDeviceByNameIdxKey)schema.getFactorySecDevice().newByNameIdxKey();
		keyNameIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyNameIdx.setRequiredDevName( existing.getRequiredDevName() );

		CFSecBuffSecDeviceByUserIdxKey keyUserIdx = (CFSecBuffSecDeviceByUserIdxKey)schema.getFactorySecDevice().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecDevicePKey, CFSecBuffSecDevice > subdict;

		dictByPKey.remove( pkey );

		dictByNameIdx.remove( keyNameIdx );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

	}
	public void deleteSecDeviceByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		String argDevName )
	{
		CFSecBuffSecDevicePKey key = schema.getFactorySecDevice().newPKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setRequiredDevName( argDevName );
		deleteSecDeviceByIdIdx( Authorization, key );
	}

	public void deleteSecDeviceByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecDevicePKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecDevice cur;
		LinkedList<CFSecBuffSecDevice> matchSet = new LinkedList<CFSecBuffSecDevice>();
		Iterator<CFSecBuffSecDevice> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecDevice> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecDevice)(schema.getTableSecDevice().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredDevName() ));
			deleteSecDevice( Authorization, cur );
		}
	}

	public void deleteSecDeviceByNameIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		String argDevName )
	{
		CFSecBuffSecDeviceByNameIdxKey key = (CFSecBuffSecDeviceByNameIdxKey)schema.getFactorySecDevice().newByNameIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setRequiredDevName( argDevName );
		deleteSecDeviceByNameIdx( Authorization, key );
	}

	public void deleteSecDeviceByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecDeviceByNameIdxKey argKey )
	{
		CFSecBuffSecDevice cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecDevice> matchSet = new LinkedList<CFSecBuffSecDevice>();
		Iterator<CFSecBuffSecDevice> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecDevice> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecDevice)(schema.getTableSecDevice().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredDevName() ));
			deleteSecDevice( Authorization, cur );
		}
	}

	public void deleteSecDeviceByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecBuffSecDeviceByUserIdxKey key = (CFSecBuffSecDeviceByUserIdxKey)schema.getFactorySecDevice().newByUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecDeviceByUserIdx( Authorization, key );
	}

	public void deleteSecDeviceByUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecDeviceByUserIdxKey argKey )
	{
		CFSecBuffSecDevice cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecDevice> matchSet = new LinkedList<CFSecBuffSecDevice>();
		Iterator<CFSecBuffSecDevice> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecDevice> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecDevice)(schema.getTableSecDevice().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredDevName() ));
			deleteSecDevice( Authorization, cur );
		}
	}
}
