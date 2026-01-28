
// Description: Java 25 in-memory RAM DbIO implementation for ISOCtryCcy.

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
 *	CFSecRamISOCtryCcyTable in-memory RAM DbIO implementation
 *	for ISOCtryCcy.
 */
public class CFSecRamISOCtryCcyTable
	implements ICFSecISOCtryCcyTable
{
	private ICFSecSchema schema;
	private Map< ICFSecISOCtryCcyPKey,
				CFSecBuffISOCtryCcy > dictByPKey
		= new HashMap< ICFSecISOCtryCcyPKey,
				CFSecBuffISOCtryCcy >();
	private Map< CFSecBuffISOCtryCcyByCtryIdxKey,
				Map< CFSecBuffISOCtryCcyPKey,
					CFSecBuffISOCtryCcy >> dictByCtryIdx
		= new HashMap< CFSecBuffISOCtryCcyByCtryIdxKey,
				Map< CFSecBuffISOCtryCcyPKey,
					CFSecBuffISOCtryCcy >>();
	private Map< CFSecBuffISOCtryCcyByCcyIdxKey,
				Map< CFSecBuffISOCtryCcyPKey,
					CFSecBuffISOCtryCcy >> dictByCcyIdx
		= new HashMap< CFSecBuffISOCtryCcyByCcyIdxKey,
				Map< CFSecBuffISOCtryCcyPKey,
					CFSecBuffISOCtryCcy >>();

	public CFSecRamISOCtryCcyTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffISOCtryCcy ensureRec(ICFSecISOCtryCcy rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecISOCtryCcy.CLASS_CODE) {
				return( ((CFSecBuffISOCtryCcyDefaultFactory)(schema.getFactoryISOCtryCcy())).ensureRec(rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecISOCtryCcy createISOCtryCcy( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcy iBuff )
	{
		final String S_ProcName = "createISOCtryCcy";
		
		CFSecBuffISOCtryCcy Buff = ensureRec(iBuff);
		CFSecBuffISOCtryCcyPKey pkey = (CFSecBuffISOCtryCcyPKey)(schema.getFactoryISOCtryCcy().newPKey());
		pkey.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );
		pkey.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );
		Buff.setRequiredISOCtryId( pkey.getRequiredISOCtryId() );
		Buff.setRequiredISOCcyId( pkey.getRequiredISOCcyId() );
		CFSecBuffISOCtryCcyByCtryIdxKey keyCtryIdx = (CFSecBuffISOCtryCcyByCtryIdxKey)schema.getFactoryISOCtryCcy().newByCtryIdxKey();
		keyCtryIdx.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );

		CFSecBuffISOCtryCcyByCcyIdxKey keyCcyIdx = (CFSecBuffISOCtryCcyByCcyIdxKey)schema.getFactoryISOCtryCcy().newByCcyIdxKey();
		keyCcyIdx.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
						Buff.getRequiredISOCtryId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"ISOCtryCcyCtry",
						"ISOCtryCcyCtry",
						"ISOCtry",
						"ISOCtry",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy > subdictCtryIdx;
		if( dictByCtryIdx.containsKey( keyCtryIdx ) ) {
			subdictCtryIdx = dictByCtryIdx.get( keyCtryIdx );
		}
		else {
			subdictCtryIdx = new HashMap< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy >();
			dictByCtryIdx.put( keyCtryIdx, subdictCtryIdx );
		}
		subdictCtryIdx.put( pkey, Buff );

		Map< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy > subdictCcyIdx;
		if( dictByCcyIdx.containsKey( keyCcyIdx ) ) {
			subdictCcyIdx = dictByCcyIdx.get( keyCcyIdx );
		}
		else {
			subdictCcyIdx = new HashMap< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy >();
			dictByCcyIdx.put( keyCcyIdx, subdictCcyIdx );
		}
		subdictCcyIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecISOCtryCcy.CLASS_CODE) {
				CFSecBuffISOCtryCcy retbuff = ((CFSecBuffISOCtryCcy)(schema.getFactoryISOCtryCcy().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecISOCtryCcy readDerived( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcyPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerived";
		ICFSecISOCtryCcyPKey key = schema.getFactoryISOCtryCcy().newPKey();
		key.setRequiredISOCtryId( PKey.getRequiredISOCtryId() );
		key.setRequiredISOCcyId( PKey.getRequiredISOCcyId() );
		ICFSecISOCtryCcy buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryCcy lockDerived( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcyPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerived";
		CFSecBuffISOCtryCcyPKey key = schema.getFactoryISOCtryCcy().newPKey();
		key.setRequiredISOCtryId( PKey.getRequiredISOCtryId() );
		key.setRequiredISOCcyId( PKey.getRequiredISOCcyId() );
		ICFSecISOCtryCcy buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryCcy[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOCtryCcy.readAllDerived";
		ICFSecISOCtryCcy[] retList = new ICFSecISOCtryCcy[ dictByPKey.values().size() ];
		Iterator< CFSecBuffISOCtryCcy > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecISOCtryCcy[] readDerivedByCtryIdx( ICFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerivedByCtryIdx";
		CFSecBuffISOCtryCcyByCtryIdxKey key = (CFSecBuffISOCtryCcyByCtryIdxKey)schema.getFactoryISOCtryCcy().newByCtryIdxKey();
		key.setRequiredISOCtryId( ISOCtryId );

		ICFSecISOCtryCcy[] recArray;
		if( dictByCtryIdx.containsKey( key ) ) {
			Map< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy > subdictCtryIdx
				= dictByCtryIdx.get( key );
			recArray = new ICFSecISOCtryCcy[ subdictCtryIdx.size() ];
			Iterator< CFSecBuffISOCtryCcy > iter = subdictCtryIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy > subdictCtryIdx
				= new HashMap< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy >();
			dictByCtryIdx.put( key, subdictCtryIdx );
			recArray = new ICFSecISOCtryCcy[0];
		}
		return( recArray );
	}

	public ICFSecISOCtryCcy[] readDerivedByCcyIdx( ICFSecAuthorization Authorization,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerivedByCcyIdx";
		CFSecBuffISOCtryCcyByCcyIdxKey key = (CFSecBuffISOCtryCcyByCcyIdxKey)schema.getFactoryISOCtryCcy().newByCcyIdxKey();
		key.setRequiredISOCcyId( ISOCcyId );

		ICFSecISOCtryCcy[] recArray;
		if( dictByCcyIdx.containsKey( key ) ) {
			Map< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy > subdictCcyIdx
				= dictByCcyIdx.get( key );
			recArray = new ICFSecISOCtryCcy[ subdictCcyIdx.size() ];
			Iterator< CFSecBuffISOCtryCcy > iter = subdictCcyIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy > subdictCcyIdx
				= new HashMap< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy >();
			dictByCcyIdx.put( key, subdictCcyIdx );
			recArray = new ICFSecISOCtryCcy[0];
		}
		return( recArray );
	}

	public ICFSecISOCtryCcy readDerivedByIdIdx( ICFSecAuthorization Authorization,
		short ISOCtryId,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerivedByIdIdx() ";
		CFSecBuffISOCtryCcyPKey key = schema.getFactoryISOCtryCcy().newPKey();
		key.setRequiredISOCtryId( ISOCtryId );
		key.setRequiredISOCcyId( ISOCcyId );

		ICFSecISOCtryCcy buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryCcy readRec( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcyPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readRec";
		ICFSecISOCtryCcy buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOCtryCcy.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryCcy lockRec( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcyPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecISOCtryCcy buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOCtryCcy.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryCcy[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readAllRec";
		ICFSecISOCtryCcy buff;
		ArrayList<ICFSecISOCtryCcy> filteredList = new ArrayList<ICFSecISOCtryCcy>();
		ICFSecISOCtryCcy[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtryCcy.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOCtryCcy[0] ) );
	}

	public ICFSecISOCtryCcy readRecByIdIdx( ICFSecAuthorization Authorization,
		short ISOCtryId,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readRecByIdIdx() ";
		ICFSecISOCtryCcy buff = readDerivedByIdIdx( Authorization,
			ISOCtryId,
			ISOCcyId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtryCcy.CLASS_CODE ) ) {
			return( (ICFSecISOCtryCcy)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOCtryCcy[] readRecByCtryIdx( ICFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readRecByCtryIdx() ";
		ICFSecISOCtryCcy buff;
		ArrayList<ICFSecISOCtryCcy> filteredList = new ArrayList<ICFSecISOCtryCcy>();
		ICFSecISOCtryCcy[] buffList = readDerivedByCtryIdx( Authorization,
			ISOCtryId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtryCcy.CLASS_CODE ) ) {
				filteredList.add( (ICFSecISOCtryCcy)buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOCtryCcy[0] ) );
	}

	public ICFSecISOCtryCcy[] readRecByCcyIdx( ICFSecAuthorization Authorization,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readRecByCcyIdx() ";
		ICFSecISOCtryCcy buff;
		ArrayList<ICFSecISOCtryCcy> filteredList = new ArrayList<ICFSecISOCtryCcy>();
		ICFSecISOCtryCcy[] buffList = readDerivedByCcyIdx( Authorization,
			ISOCcyId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtryCcy.CLASS_CODE ) ) {
				filteredList.add( (ICFSecISOCtryCcy)buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOCtryCcy[0] ) );
	}

	public ICFSecISOCtryCcy updateISOCtryCcy( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcy iBuff )
	{
		CFSecBuffISOCtryCcy Buff = ensureRec(iBuff);
		CFSecBuffISOCtryCcyPKey pkey = (CFSecBuffISOCtryCcyPKey)schema.getFactoryISOCtryCcy().newPKey();
		pkey.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );
		pkey.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );
		CFSecBuffISOCtryCcy existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOCtryCcy",
				"Existing record not found",
				"Existing record not found",
				"ISOCtryCcy",
				"ISOCtryCcy",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOCtryCcy",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffISOCtryCcyByCtryIdxKey existingKeyCtryIdx = (CFSecBuffISOCtryCcyByCtryIdxKey)schema.getFactoryISOCtryCcy().newByCtryIdxKey();
		existingKeyCtryIdx.setRequiredISOCtryId( existing.getRequiredISOCtryId() );

		CFSecBuffISOCtryCcyByCtryIdxKey newKeyCtryIdx = (CFSecBuffISOCtryCcyByCtryIdxKey)schema.getFactoryISOCtryCcy().newByCtryIdxKey();
		newKeyCtryIdx.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );

		CFSecBuffISOCtryCcyByCcyIdxKey existingKeyCcyIdx = (CFSecBuffISOCtryCcyByCcyIdxKey)schema.getFactoryISOCtryCcy().newByCcyIdxKey();
		existingKeyCcyIdx.setRequiredISOCcyId( existing.getRequiredISOCcyId() );

		CFSecBuffISOCtryCcyByCcyIdxKey newKeyCcyIdx = (CFSecBuffISOCtryCcyByCcyIdxKey)schema.getFactoryISOCtryCcy().newByCcyIdxKey();
		newKeyCcyIdx.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
						Buff.getRequiredISOCtryId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateISOCtryCcy",
						"Container",
						"Container",
						"ISOCtryCcyCtry",
						"ISOCtryCcyCtry",
						"ISOCtry",
						"ISOCtry",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByCtryIdx.get( existingKeyCtryIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByCtryIdx.containsKey( newKeyCtryIdx ) ) {
			subdict = dictByCtryIdx.get( newKeyCtryIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy >();
			dictByCtryIdx.put( newKeyCtryIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByCcyIdx.get( existingKeyCcyIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByCcyIdx.containsKey( newKeyCcyIdx ) ) {
			subdict = dictByCcyIdx.get( newKeyCcyIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy >();
			dictByCcyIdx.put( newKeyCcyIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	public void deleteISOCtryCcy( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcy iBuff )
	{
		final String S_ProcName = "CFSecRamISOCtryCcyTable.deleteISOCtryCcy() ";
		CFSecBuffISOCtryCcy Buff = ensureRec(iBuff);
		int classCode;
		CFSecBuffISOCtryCcyPKey pkey = (CFSecBuffISOCtryCcyPKey)(Buff.getPKey());
		CFSecBuffISOCtryCcy existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOCtryCcy",
				pkey );
		}
		CFSecBuffISOCtryCcyByCtryIdxKey keyCtryIdx = (CFSecBuffISOCtryCcyByCtryIdxKey)schema.getFactoryISOCtryCcy().newByCtryIdxKey();
		keyCtryIdx.setRequiredISOCtryId( existing.getRequiredISOCtryId() );

		CFSecBuffISOCtryCcyByCcyIdxKey keyCcyIdx = (CFSecBuffISOCtryCcyByCcyIdxKey)schema.getFactoryISOCtryCcy().newByCcyIdxKey();
		keyCcyIdx.setRequiredISOCcyId( existing.getRequiredISOCcyId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffISOCtryCcyPKey, CFSecBuffISOCtryCcy > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByCtryIdx.get( keyCtryIdx );
		subdict.remove( pkey );

		subdict = dictByCcyIdx.get( keyCcyIdx );
		subdict.remove( pkey );

	}
	public void deleteISOCtryCcyByIdIdx( ICFSecAuthorization Authorization,
		short argISOCtryId,
		short argISOCcyId )
	{
		CFSecBuffISOCtryCcyPKey key = schema.getFactoryISOCtryCcy().newPKey();
		key.setRequiredISOCtryId( argISOCtryId );
		key.setRequiredISOCcyId( argISOCcyId );
		deleteISOCtryCcyByIdIdx( Authorization, key );
	}

	public void deleteISOCtryCcyByIdIdx( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcyPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffISOCtryCcy cur;
		LinkedList<CFSecBuffISOCtryCcy> matchSet = new LinkedList<CFSecBuffISOCtryCcy>();
		Iterator<CFSecBuffISOCtryCcy> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCtryCcy> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCtryCcy)(schema.getTableISOCtryCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId(),
				cur.getRequiredISOCcyId() ));
			deleteISOCtryCcy( Authorization, cur );
		}
	}

	public void deleteISOCtryCcyByCtryIdx( ICFSecAuthorization Authorization,
		short argISOCtryId )
	{
		CFSecBuffISOCtryCcyByCtryIdxKey key = (CFSecBuffISOCtryCcyByCtryIdxKey)schema.getFactoryISOCtryCcy().newByCtryIdxKey();
		key.setRequiredISOCtryId( argISOCtryId );
		deleteISOCtryCcyByCtryIdx( Authorization, key );
	}

	public void deleteISOCtryCcyByCtryIdx( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcyByCtryIdxKey argKey )
	{
		CFSecBuffISOCtryCcy cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOCtryCcy> matchSet = new LinkedList<CFSecBuffISOCtryCcy>();
		Iterator<CFSecBuffISOCtryCcy> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCtryCcy> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCtryCcy)(schema.getTableISOCtryCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId(),
				cur.getRequiredISOCcyId() ));
			deleteISOCtryCcy( Authorization, cur );
		}
	}

	public void deleteISOCtryCcyByCcyIdx( ICFSecAuthorization Authorization,
		short argISOCcyId )
	{
		CFSecBuffISOCtryCcyByCcyIdxKey key = (CFSecBuffISOCtryCcyByCcyIdxKey)schema.getFactoryISOCtryCcy().newByCcyIdxKey();
		key.setRequiredISOCcyId( argISOCcyId );
		deleteISOCtryCcyByCcyIdx( Authorization, key );
	}

	public void deleteISOCtryCcyByCcyIdx( ICFSecAuthorization Authorization,
		ICFSecISOCtryCcyByCcyIdxKey argKey )
	{
		CFSecBuffISOCtryCcy cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOCtryCcy> matchSet = new LinkedList<CFSecBuffISOCtryCcy>();
		Iterator<CFSecBuffISOCtryCcy> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCtryCcy> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCtryCcy)(schema.getTableISOCtryCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId(),
				cur.getRequiredISOCcyId() ));
			deleteISOCtryCcy( Authorization, cur );
		}
	}
}
