
// Description: Java 25 in-memory RAM DbIO implementation for SecUser.

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
 *	CFSecRamSecUserTable in-memory RAM DbIO implementation
 *	for SecUser.
 */
public class CFSecRamSecUserTable
	implements ICFSecSecUserTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffSecUser > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffSecUser >();
	private Map< CFSecBuffSecUserByULoginIdxKey,
			CFSecBuffSecUser > dictByULoginIdx
		= new HashMap< CFSecBuffSecUserByULoginIdxKey,
			CFSecBuffSecUser >();
	private Map< CFSecBuffSecUserByEMConfIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >> dictByEMConfIdx
		= new HashMap< CFSecBuffSecUserByEMConfIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >>();
	private Map< CFSecBuffSecUserByPwdResetIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >> dictByPwdResetIdx
		= new HashMap< CFSecBuffSecUserByPwdResetIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >>();
	private Map< CFSecBuffSecUserByDefDevIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >> dictByDefDevIdx
		= new HashMap< CFSecBuffSecUserByDefDevIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >>();

	public CFSecRamSecUserTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecUser ensureRec(ICFSecSecUser rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecUser.CLASS_CODE) {
				return( ((CFSecBuffSecUserDefaultFactory)(schema.getFactorySecUser())).ensureRec((ICFSecSecUser)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecUser createSecUser( ICFSecAuthorization Authorization,
		ICFSecSecUser iBuff )
	{
		final String S_ProcName = "createSecUser";
		
		CFSecBuffSecUser Buff = (CFSecBuffSecUser)ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextSecUserIdGen();
		Buff.setRequiredSecUserId( pkey );
		CFSecBuffSecUserByULoginIdxKey keyULoginIdx = (CFSecBuffSecUserByULoginIdxKey)schema.getFactorySecUser().newByULoginIdxKey();
		keyULoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		CFSecBuffSecUserByEMConfIdxKey keyEMConfIdx = (CFSecBuffSecUserByEMConfIdxKey)schema.getFactorySecUser().newByEMConfIdxKey();
		keyEMConfIdx.setOptionalEMailConfirmUuid6( Buff.getOptionalEMailConfirmUuid6() );

		CFSecBuffSecUserByPwdResetIdxKey keyPwdResetIdx = (CFSecBuffSecUserByPwdResetIdxKey)schema.getFactorySecUser().newByPwdResetIdxKey();
		keyPwdResetIdx.setOptionalPasswordResetUuid6( Buff.getOptionalPasswordResetUuid6() );

		CFSecBuffSecUserByDefDevIdxKey keyDefDevIdx = (CFSecBuffSecUserByDefDevIdxKey)schema.getFactorySecUser().newByDefDevIdxKey();
		keyDefDevIdx.setOptionalDfltDevUserId( Buff.getOptionalDfltDevUserId() );
		keyDefDevIdx.setOptionalDfltDevName( Buff.getOptionalDfltDevName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByULoginIdx.containsKey( keyULoginIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecUserLoginIdx",
				"SecUserLoginIdx",
				keyULoginIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByULoginIdx.put( keyULoginIdx, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictEMConfIdx;
		if( dictByEMConfIdx.containsKey( keyEMConfIdx ) ) {
			subdictEMConfIdx = dictByEMConfIdx.get( keyEMConfIdx );
		}
		else {
			subdictEMConfIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByEMConfIdx.put( keyEMConfIdx, subdictEMConfIdx );
		}
		subdictEMConfIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictPwdResetIdx;
		if( dictByPwdResetIdx.containsKey( keyPwdResetIdx ) ) {
			subdictPwdResetIdx = dictByPwdResetIdx.get( keyPwdResetIdx );
		}
		else {
			subdictPwdResetIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByPwdResetIdx.put( keyPwdResetIdx, subdictPwdResetIdx );
		}
		subdictPwdResetIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictDefDevIdx;
		if( dictByDefDevIdx.containsKey( keyDefDevIdx ) ) {
			subdictDefDevIdx = dictByDefDevIdx.get( keyDefDevIdx );
		}
		else {
			subdictDefDevIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByDefDevIdx.put( keyDefDevIdx, subdictDefDevIdx );
		}
		subdictDefDevIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecUser.CLASS_CODE) {
				CFSecBuffSecUser retbuff = ((CFSecBuffSecUser)(schema.getFactorySecUser().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecUser readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerived";
		ICFSecSecUser buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.lockDerived";
		ICFSecSecUser buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecUser.readAllDerived";
		ICFSecSecUser[] retList = new ICFSecSecUser[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecUser > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecUser readDerivedByULoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByULoginIdx";
		CFSecBuffSecUserByULoginIdxKey key = (CFSecBuffSecUserByULoginIdxKey)schema.getFactorySecUser().newByULoginIdxKey();

		key.setRequiredLoginId( LoginId );
		ICFSecSecUser buff;
		if( dictByULoginIdx.containsKey( key ) ) {
			buff = dictByULoginIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser[] readDerivedByEMConfIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 EMailConfirmUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByEMConfIdx";
		CFSecBuffSecUserByEMConfIdxKey key = (CFSecBuffSecUserByEMConfIdxKey)schema.getFactorySecUser().newByEMConfIdxKey();

		key.setOptionalEMailConfirmUuid6( EMailConfirmUuid6 );
		ICFSecSecUser[] recArray;
		if( dictByEMConfIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictEMConfIdx
				= dictByEMConfIdx.get( key );
			recArray = new ICFSecSecUser[ subdictEMConfIdx.size() ];
			Iterator< CFSecBuffSecUser > iter = subdictEMConfIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictEMConfIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByEMConfIdx.put( key, subdictEMConfIdx );
			recArray = new ICFSecSecUser[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUser[] readDerivedByPwdResetIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 PasswordResetUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByPwdResetIdx";
		CFSecBuffSecUserByPwdResetIdxKey key = (CFSecBuffSecUserByPwdResetIdxKey)schema.getFactorySecUser().newByPwdResetIdxKey();

		key.setOptionalPasswordResetUuid6( PasswordResetUuid6 );
		ICFSecSecUser[] recArray;
		if( dictByPwdResetIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictPwdResetIdx
				= dictByPwdResetIdx.get( key );
			recArray = new ICFSecSecUser[ subdictPwdResetIdx.size() ];
			Iterator< CFSecBuffSecUser > iter = subdictPwdResetIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictPwdResetIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByPwdResetIdx.put( key, subdictPwdResetIdx );
			recArray = new ICFSecSecUser[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUser[] readDerivedByDefDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 DfltDevUserId,
		String DfltDevName )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByDefDevIdx";
		CFSecBuffSecUserByDefDevIdxKey key = (CFSecBuffSecUserByDefDevIdxKey)schema.getFactorySecUser().newByDefDevIdxKey();

		key.setOptionalDfltDevUserId( DfltDevUserId );
		key.setOptionalDfltDevName( DfltDevName );
		ICFSecSecUser[] recArray;
		if( dictByDefDevIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictDefDevIdx
				= dictByDefDevIdx.get( key );
			recArray = new ICFSecSecUser[ subdictDefDevIdx.size() ];
			Iterator< CFSecBuffSecUser > iter = subdictDefDevIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictDefDevIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByDefDevIdx.put( key, subdictDefDevIdx );
			recArray = new ICFSecSecUser[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUser readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByIdIdx() ";
		ICFSecSecUser buff;
		if( dictByPKey.containsKey( SecUserId ) ) {
			buff = dictByPKey.get( SecUserId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readRec";
		ICFSecSecUser buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUser.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser lockRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecUser buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUser.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecUser.readAllRec";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	/**
	 *	Read a page of all the specific SecUser buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecUser instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecUser[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecUser readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUser.readRecByIdIdx() ";
		ICFSecSecUser buff = readDerivedByIdIdx( Authorization,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
			return( (ICFSecSecUser)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUser readRecByULoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecUser.readRecByULoginIdx() ";
		ICFSecSecUser buff = readDerivedByULoginIdx( Authorization,
			LoginId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
			return( (ICFSecSecUser)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUser[] readRecByEMConfIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 EMailConfirmUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readRecByEMConfIdx() ";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readDerivedByEMConfIdx( Authorization,
			EMailConfirmUuid6 );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUser)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	@Override
	public ICFSecSecUser[] readRecByPwdResetIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 PasswordResetUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readRecByPwdResetIdx() ";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readDerivedByPwdResetIdx( Authorization,
			PasswordResetUuid6 );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUser)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	@Override
	public ICFSecSecUser[] readRecByDefDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 DfltDevUserId,
		String DfltDevName )
	{
		final String S_ProcName = "CFSecRamSecUser.readRecByDefDevIdx() ";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readDerivedByDefDevIdx( Authorization,
			DfltDevUserId,
			DfltDevName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUser)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key EMConfIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMailConfirmUuid6	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUser[] pageRecByEMConfIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 EMailConfirmUuid6,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByEMConfIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key PwdResetIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PasswordResetUuid6	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUser[] pageRecByPwdResetIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 PasswordResetUuid6,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByPwdResetIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key DefDevIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	DfltDevUserId	The SecUser key attribute of the instance generating the id.
	 *
	 *	@param	DfltDevName	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUser[] pageRecByDefDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 DfltDevUserId,
		String DfltDevName,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByDefDevIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecUser updateSecUser( ICFSecAuthorization Authorization,
		ICFSecSecUser iBuff )
	{
		CFSecBuffSecUser Buff = (CFSecBuffSecUser)ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffSecUser existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecUser",
				"Existing record not found",
				"Existing record not found",
				"SecUser",
				"SecUser",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecUser",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecUserByULoginIdxKey existingKeyULoginIdx = (CFSecBuffSecUserByULoginIdxKey)schema.getFactorySecUser().newByULoginIdxKey();
		existingKeyULoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecUserByULoginIdxKey newKeyULoginIdx = (CFSecBuffSecUserByULoginIdxKey)schema.getFactorySecUser().newByULoginIdxKey();
		newKeyULoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		CFSecBuffSecUserByEMConfIdxKey existingKeyEMConfIdx = (CFSecBuffSecUserByEMConfIdxKey)schema.getFactorySecUser().newByEMConfIdxKey();
		existingKeyEMConfIdx.setOptionalEMailConfirmUuid6( existing.getOptionalEMailConfirmUuid6() );

		CFSecBuffSecUserByEMConfIdxKey newKeyEMConfIdx = (CFSecBuffSecUserByEMConfIdxKey)schema.getFactorySecUser().newByEMConfIdxKey();
		newKeyEMConfIdx.setOptionalEMailConfirmUuid6( Buff.getOptionalEMailConfirmUuid6() );

		CFSecBuffSecUserByPwdResetIdxKey existingKeyPwdResetIdx = (CFSecBuffSecUserByPwdResetIdxKey)schema.getFactorySecUser().newByPwdResetIdxKey();
		existingKeyPwdResetIdx.setOptionalPasswordResetUuid6( existing.getOptionalPasswordResetUuid6() );

		CFSecBuffSecUserByPwdResetIdxKey newKeyPwdResetIdx = (CFSecBuffSecUserByPwdResetIdxKey)schema.getFactorySecUser().newByPwdResetIdxKey();
		newKeyPwdResetIdx.setOptionalPasswordResetUuid6( Buff.getOptionalPasswordResetUuid6() );

		CFSecBuffSecUserByDefDevIdxKey existingKeyDefDevIdx = (CFSecBuffSecUserByDefDevIdxKey)schema.getFactorySecUser().newByDefDevIdxKey();
		existingKeyDefDevIdx.setOptionalDfltDevUserId( existing.getOptionalDfltDevUserId() );
		existingKeyDefDevIdx.setOptionalDfltDevName( existing.getOptionalDfltDevName() );

		CFSecBuffSecUserByDefDevIdxKey newKeyDefDevIdx = (CFSecBuffSecUserByDefDevIdxKey)schema.getFactorySecUser().newByDefDevIdxKey();
		newKeyDefDevIdx.setOptionalDfltDevUserId( Buff.getOptionalDfltDevUserId() );
		newKeyDefDevIdx.setOptionalDfltDevName( Buff.getOptionalDfltDevName() );

		// Check unique indexes

		if( ! existingKeyULoginIdx.equals( newKeyULoginIdx ) ) {
			if( dictByULoginIdx.containsKey( newKeyULoginIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecUser",
					"SecUserLoginIdx",
					"SecUserLoginIdx",
					newKeyULoginIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByULoginIdx.remove( existingKeyULoginIdx );
		dictByULoginIdx.put( newKeyULoginIdx, Buff );

		subdict = dictByEMConfIdx.get( existingKeyEMConfIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByEMConfIdx.containsKey( newKeyEMConfIdx ) ) {
			subdict = dictByEMConfIdx.get( newKeyEMConfIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByEMConfIdx.put( newKeyEMConfIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByPwdResetIdx.get( existingKeyPwdResetIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByPwdResetIdx.containsKey( newKeyPwdResetIdx ) ) {
			subdict = dictByPwdResetIdx.get( newKeyPwdResetIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByPwdResetIdx.put( newKeyPwdResetIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByDefDevIdx.get( existingKeyDefDevIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByDefDevIdx.containsKey( newKeyDefDevIdx ) ) {
			subdict = dictByDefDevIdx.get( newKeyDefDevIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByDefDevIdx.put( newKeyDefDevIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecUser( ICFSecAuthorization Authorization,
		ICFSecSecUser iBuff )
	{
		final String S_ProcName = "CFSecRamSecUserTable.deleteSecUser() ";
		CFSecBuffSecUser Buff = (CFSecBuffSecUser)ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffSecUser existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecUser",
				pkey );
		}
					{
						CFSecBuffSecUser editBuff = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						existing.getRequiredSecUserId() ));
						editBuff.setOptionalLookupDefDev((CFLibDbKeyHash256)null, (String)null);
						classCode = editBuff.getClassCode();
						if( classCode == ICFSecSecUser.CLASS_CODE ) {
							schema.getTableSecUser().updateSecUser( Authorization, editBuff );
						}
						else {
							throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-delete-clear-top-dep-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
						}
					}
		CFSecBuffSecUser editSubobj = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
			existing.getRequiredSecUserId() ));
			editSubobj.setOptionalLookupDefDev((CFLibDbKeyHash256)null, (String)null);
		classCode = editSubobj.getClassCode();
		if( classCode == ICFSecSecUser.CLASS_CODE ) {
			schema.getTableSecUser().updateSecUser( Authorization, editSubobj );
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-delete-clear-root-subobject-refs-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
		}
		existing = editSubobj;
					schema.getTableTSecGrpMemb().deleteTSecGrpMembByUserIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecGrpMemb().deleteSecGrpMembByUserIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecSession().deleteSecSessionBySecUserIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecSession().deleteSecSessionBySecProxyIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecDevice().deleteSecDeviceByUserIdx( Authorization,
						existing.getRequiredSecUserId() );
		CFSecBuffSecUserByULoginIdxKey keyULoginIdx = (CFSecBuffSecUserByULoginIdxKey)schema.getFactorySecUser().newByULoginIdxKey();
		keyULoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecUserByEMConfIdxKey keyEMConfIdx = (CFSecBuffSecUserByEMConfIdxKey)schema.getFactorySecUser().newByEMConfIdxKey();
		keyEMConfIdx.setOptionalEMailConfirmUuid6( existing.getOptionalEMailConfirmUuid6() );

		CFSecBuffSecUserByPwdResetIdxKey keyPwdResetIdx = (CFSecBuffSecUserByPwdResetIdxKey)schema.getFactorySecUser().newByPwdResetIdxKey();
		keyPwdResetIdx.setOptionalPasswordResetUuid6( existing.getOptionalPasswordResetUuid6() );

		CFSecBuffSecUserByDefDevIdxKey keyDefDevIdx = (CFSecBuffSecUserByDefDevIdxKey)schema.getFactorySecUser().newByDefDevIdxKey();
		keyDefDevIdx.setOptionalDfltDevUserId( existing.getOptionalDfltDevUserId() );
		keyDefDevIdx.setOptionalDfltDevName( existing.getOptionalDfltDevName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdict;

		dictByPKey.remove( pkey );

		dictByULoginIdx.remove( keyULoginIdx );

		subdict = dictByEMConfIdx.get( keyEMConfIdx );
		subdict.remove( pkey );

		subdict = dictByPwdResetIdx.get( keyPwdResetIdx );
		subdict.remove( pkey );

		subdict = dictByDefDevIdx.get( keyDefDevIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecUserByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecUser cur;
		LinkedList<CFSecBuffSecUser> matchSet = new LinkedList<CFSecBuffSecUser>();
		Iterator<CFSecBuffSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUser( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserByULoginIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		CFSecBuffSecUserByULoginIdxKey key = (CFSecBuffSecUserByULoginIdxKey)schema.getFactorySecUser().newByULoginIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecUserByULoginIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserByULoginIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByULoginIdxKey argKey )
	{
		CFSecBuffSecUser cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUser> matchSet = new LinkedList<CFSecBuffSecUser>();
		Iterator<CFSecBuffSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUser( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserByEMConfIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 argEMailConfirmUuid6 )
	{
		CFSecBuffSecUserByEMConfIdxKey key = (CFSecBuffSecUserByEMConfIdxKey)schema.getFactorySecUser().newByEMConfIdxKey();
		key.setOptionalEMailConfirmUuid6( argEMailConfirmUuid6 );
		deleteSecUserByEMConfIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserByEMConfIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByEMConfIdxKey argKey )
	{
		CFSecBuffSecUser cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalEMailConfirmUuid6() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUser> matchSet = new LinkedList<CFSecBuffSecUser>();
		Iterator<CFSecBuffSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUser( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserByPwdResetIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 argPasswordResetUuid6 )
	{
		CFSecBuffSecUserByPwdResetIdxKey key = (CFSecBuffSecUserByPwdResetIdxKey)schema.getFactorySecUser().newByPwdResetIdxKey();
		key.setOptionalPasswordResetUuid6( argPasswordResetUuid6 );
		deleteSecUserByPwdResetIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserByPwdResetIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByPwdResetIdxKey argKey )
	{
		CFSecBuffSecUser cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalPasswordResetUuid6() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUser> matchSet = new LinkedList<CFSecBuffSecUser>();
		Iterator<CFSecBuffSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUser( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserByDefDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argDfltDevUserId,
		String argDfltDevName )
	{
		CFSecBuffSecUserByDefDevIdxKey key = (CFSecBuffSecUserByDefDevIdxKey)schema.getFactorySecUser().newByDefDevIdxKey();
		key.setOptionalDfltDevUserId( argDfltDevUserId );
		key.setOptionalDfltDevName( argDfltDevName );
		deleteSecUserByDefDevIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserByDefDevIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByDefDevIdxKey argKey )
	{
		CFSecBuffSecUser cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalDfltDevUserId() != null ) {
			anyNotNull = true;
		}
		if( argKey.getOptionalDfltDevName() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUser> matchSet = new LinkedList<CFSecBuffSecUser>();
		Iterator<CFSecBuffSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUser( Authorization, cur );
		}
	}
}
